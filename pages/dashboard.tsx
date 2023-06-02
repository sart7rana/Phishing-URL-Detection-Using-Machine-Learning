import Head from "next/head";
import { Table, Button, Modal, ConfigProvider } from "antd";
import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import store from "store";

export default function DashBoard() {
    const router = useRouter();
    useEffect(() => {
        const initialData = store.get("dashboardDb") ?? [];
        if (store.get("searchScan")) {
            initialData.push(store.get("searchScan"));
            setActiveDetails(store.get("searchScan"));
            store.set("searchScan", undefined);
        }
        setDataSource(initialData)
        if ((Object.keys(activeDetails).length === 0)) {
            setActiveDetails(initialData[0])
        }
        store.set("dashboardDb", initialData)
        setFirstRender(false);
    }, [])

    const [activeDetails, setActiveDetails] = useState({});

    const [showModal, setShowModal] = useState(false)
    const [firstRender, setFirstRender] = useState(true);

    const [dataSource, setDataSource] = useState([])
    return <>
        <Head>
            <title>DashBoard | Sarthak Rana</title>
        </Head>
        {!firstRender &&
            <main className="bg-slate-100 min-h-screen pt-12 px-24">
                <Modal open={showModal} footer={null} width="750" centered onCancel={() => { setShowModal(false) }}>
                    <main className="m-6 grid grid-cols-2 gap-4">
                        <div className="w-96 border flex flex-col gap-6 p-4">
                            <div className="">
                                <div className="text-black/60 font-bold">Source URL:</div>
                                <a href={activeDetails.source_url} className="">{activeDetails.source_url}</a>
                            </div>
                            <div className="grid grid-cols-2">
                                <div className="">
                                    <div className="text-black/60 font-bold">IP Address:</div>
                                    <a href={activeDetails["ip-address"]} className="">{activeDetails["ip-address"]}</a>
                                </div>
                                <div className="">
                                    <div className="text-black/60 font-bold">Status:</div>
                                    <div className="text-black/60 font-medium">{activeDetails.predication}</div>
                                </div>
                            </div>
                            <div className="grid grid-cols-2">
                                <div className="">
                                    <div className="text-black/60 font-bold">Location:</div>
                                    <div className="text-black/60 font-medium">{activeDetails["location_details"].capital}</div>
                                </div>
                                <div className="">
                                    <div className="text-black/60 font-bold">Domain:</div>
                                    <div className="text-black/60 font-medium">{activeDetails.domain}</div>
                                </div>
                            </div>
                            <div className="grid grid-cols-2">
                                <div className="">
                                    <div className="text-black/60 font-bold">First Submission:</div>
                                    <div className="text-black/60 font-medium">{new Date(activeDetails["virus-total-data"].firstSubmission * 1000).toDateString()}</div>
                                </div>
                            </div>
                            <div className="grid grid-cols-2">
                                <div className="">
                                    <div className="text-black/60 font-bold">Last Submission:</div>
                                    <div className="text-black/60 font-medium">{new Date(activeDetails["virus-total-data"].lastSubmission * 1000).toDateString()}</div>
                                </div>
                            </div>
                        </div>
                        <div className="w-96 h-96 border p-4 overflow-hidden">
                            <h3 className="text-black/60 font-bold">Vendors:</h3>
                            <div className=" overflow-scroll h-full w-full divide-y divide-solid divide-black/10">
                               
                            {Object.entries(activeDetails["virus-total-data"]["last_analysis_results"]).map((data, index) => {
                                return <div key={index} className="grid grid-cols-2 py-2">
                                    <div className="">{data[0]}</div>
                                    <div className="">{data[1].result}</div>
                                </div>
                            })}
                            </div>
                          
                        </div>
                        <div className="w-96 h-96 border">
                            <img className="h-full w-full object-fit" src={activeDetails["location_details"]["screenshot_url"]} alt="" />
                        </div>
                        <div className="w-96 h-96 border">
                            <iframe
                                className="w-full h-full"
                                frameborder="0"
                                marginheight="0"
                                marginwidth="0"
                                src={`https://www.google.com/maps/embed/v1/search?key=AIzaSyCcvA7rnY_w30l6wnb0Ng7T4o-jJMlbKJ0&q=${activeDetails["location_details"]["latitude"]},${activeDetails["location_details"]["longitude"]}`}
                            >
                            </iframe>
                        </div>
                    </main>
                </Modal>
                <h1 className="text-7xl text-black/70 font-bold">Dashboard</h1>
                <div className="flex flex-row-reverse w-full mb-4">
                    <ConfigProvider theme={{ token: { colorPrimary: "#0369a1" } }}>
                        <Button className="" type="primary" onClick={() => { router.push("/") }}><span className='px-8 font-bold'>Scan New URL</span></Button>
                    </ConfigProvider>
                </div>
                <div className="p-8 bg-gradient-to-t from-sky-500 to-sky-700 my-6 rounded-lg flex text-white relative items-center divide-x-2 divide-slate-300/60">
                    <div className="top-2 mr-8 left-4 bg-white p-4 text-black/60 text-2xl shadow-slate-500/50 font-bold rounded-xl shadow-md">
                        {activeDetails["virus-total-data"]['last_analysis_stats'].malicious}
                    </div>
                    <div className="flex gap-2 items-start flex-col w-full px-12">
                        <div className="text-2xl font-semibold text-white/90">URL:</div>
                        <a href={activeDetails.source_url} className="text-lg text-gray-100">{activeDetails.source_url}</a>
                    </div>
                    <div className="flex gap-2 items-start flex-col w-full px-12">
                        <div className="text-xl font-medium text-white/90">Model Predication:</div>
                        <div className="font-medium text-lg text-white/90">{activeDetails.predication}</div>
                    </div>
                </div>
                <div className="w-full">
                    <Table
                        columns={[{
                            dataIndex: "source_url"
                            , title: "Source Url",
                            render: (data: string) => {
                                return <a href={data} className="text-blue-400">{data}</a>
                            }
                        },
                        { dataIndex: "ip-address", title: "IP Address" }

                            , { dataIndex: "domain", title: "Domain" },
                        {
                            dataIndex: "predication",
                            title: "Original Deposition",
                            render: (data: string) => { return <article className={`${data === "Legitimate" ? "text-green-500" : "text-red-400"}`}>{data}</article> }
                        },
                        {
                            dataIndex: "virus-total-data",
                            title: "Detection Date",
                            render: (data: any) => { return <article>{new Date(data["detectionDate"]).toDateString()}</article> }
                        },
                        {
                            dataIndex: "action",
                            title: "Action",
                            render: function (_, data) {
                                // console.log(data);
                                return <div className="flex gap-4">
                                    <Button onClick={() => { setActiveDetails(data) }}>Info</Button>
                                    <Button onClick={() => { setActiveDetails(data);setShowModal(true) }}>Details</Button>
                                </div>
                            }
                        }
                        ]}
                        dataSource={dataSource}
                        tableLayout="fixed"
                    ></Table>
                </div>
            </main>
        }
    </>
}